// LinuxTCPServer.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Logging
import NIOCore
import NIOPosix
import HAPCore
import HAPCrypto
import HAPTransport

// MARK: - LinuxTCPServer

public final class LinuxTCPServer: HAPServer, @unchecked Sendable {
    private let lock = NSLock()
    private let group: MultiThreadedEventLoopGroup
    private var channel: Channel?
    private let logger: Logger
    private let characteristicProtocol: CharacteristicProtocol
    private var _port: UInt16 = 0

    public var port: UInt16 {
        lock.withLock { _port }
    }

    public init(
        bridge: HAPBridge,
        setupCode: String,
        identity: HAPIdentity,
        pairingStore: any PairingStore,
        logger: Logger = Logger(label: "hap.linux.tcp")
    ) {
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        self.logger = logger

        let pairingStateMachine = PairingStateMachine(
            setupCode: setupCode, identity: identity, pairingStore: pairingStore
        )
        let pairVerifyStateMachine = PairVerifyStateMachine(
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
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 256)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { [characteristicProtocol, logger] channel in
                channel.pipeline.addHandler(
                    HAPChannelHandler(
                        characteristicProtocol: characteristicProtocol,
                        logger: logger
                    )
                )
            }
            .childChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(.maxMessagesPerRead, value: 16)

        let channel = try await bootstrap.bind(host: "::", port: Int(port)).get()

        if let localAddress = channel.localAddress, let actualPort = localAddress.port {
            lock.withLock { self._port = UInt16(actualPort) }
            logger.info("HAP server listening on port \(actualPort)")
        }

        lock.withLock { self.channel = channel }
    }

    public func stop() async {
        let currentChannel = lock.withLock {
            let ch = self.channel
            self.channel = nil
            return ch
        }

        try? await currentChannel?.close()
        try? await group.shutdownGracefully()
        logger.info("HAP server stopped")
    }
}

// MARK: - HAPChannelHandler

private final class HAPChannelHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let characteristicProtocol: CharacteristicProtocol
    private let logger: Logger
    private var buffer = Data()

    init(characteristicProtocol: CharacteristicProtocol, logger: Logger) {
        self.characteristicProtocol = characteristicProtocol
        self.logger = logger
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)
        if let bytes = buf.readBytes(length: buf.readableBytes) {
            buffer.append(contentsOf: bytes)
        }

        // Try to parse a complete HTTP request
        guard let request = HTTPProtocol.parseRequest(from: buffer) else {
            return
        }

        buffer = Data()

        let ctx = context
        Task {
            do {
                let response = try await self.characteristicProtocol.handleRequest(request)
                let responseData = HTTPProtocol.serializeResponse(response)
                ctx.eventLoop.execute {
                    var outBuf = ctx.channel.allocator.buffer(capacity: responseData.count)
                    outBuf.writeBytes(responseData)
                    ctx.writeAndFlush(self.wrapOutboundOut(outBuf), promise: nil)
                }
            } catch {
                self.logger.error("Request handling error: \(error)")
                let errorResponse = HTTPProtocol.errorResponse(status: 500, message: "Internal Server Error")
                let responseData = HTTPProtocol.serializeResponse(errorResponse)
                ctx.eventLoop.execute {
                    var outBuf = ctx.channel.allocator.buffer(capacity: responseData.count)
                    outBuf.writeBytes(responseData)
                    ctx.writeAndFlush(self.wrapOutboundOut(outBuf), promise: nil)
                }
            }
        }
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        context.flush()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.debug("Connection error: \(error)")
        context.close(promise: nil)
    }
}
