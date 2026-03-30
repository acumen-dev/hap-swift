// HTTPProtocol.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

// MARK: - HTTPRequest

public struct HTTPRequest: Sendable {
    public let method: String
    public let path: String
    public let headers: [(name: String, value: String)]
    public let body: Data

    public init(method: String, path: String, headers: [(name: String, value: String)] = [], body: Data = Data()) {
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body
    }
}

// MARK: - HTTPResponse

public struct HTTPResponse: Sendable {
    public let statusCode: Int
    public let statusMessage: String
    public let headers: [(name: String, value: String)]
    public let body: Data

    public init(statusCode: Int, statusMessage: String, headers: [(name: String, value: String)] = [], body: Data = Data()) {
        self.statusCode = statusCode
        self.statusMessage = statusMessage
        self.headers = headers
        self.body = body
    }
}

// MARK: - HTTPProtocol

public enum HTTPProtocol {

    // MARK: - Content Types

    public static let hapJSON = "application/hap+json"
    public static let pairingTLV8 = "application/pairing+tlv8"

    // MARK: - Parse Request

    public static func parseRequest(from data: Data) -> HTTPRequest? {
        guard let string = String(data: data, encoding: .utf8) else { return nil }
        let lines = string.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { return nil }

        // Request line: METHOD PATH HTTP/1.1
        let requestLine = lines[0].split(separator: " ", maxSplits: 2)
        guard requestLine.count >= 2 else { return nil }

        let method = String(requestLine[0])
        let path = String(requestLine[1])

        // Headers
        var headers: [(name: String, value: String)] = []
        for i in 1 ..< lines.count {
            if lines[i].isEmpty {
                break
            }
            if let colonIndex = lines[i].firstIndex(of: ":") {
                let name = String(lines[i][..<colonIndex]).trimmingCharacters(in: .whitespaces)
                let value = String(lines[i][lines[i].index(after: colonIndex)...]).trimmingCharacters(in: .whitespaces)
                headers.append((name: name, value: value))
            }
        }

        // Body: everything after the blank line
        var body = Data()
        if let headerEndRange = string.range(of: "\r\n\r\n") {
            let bodyString = string[headerEndRange.upperBound...]
            body = Data(bodyString.utf8)
        }

        return HTTPRequest(method: method, path: path, headers: headers, body: body)
    }

    // MARK: - Serialize Response

    public static func serializeResponse(_ response: HTTPResponse) -> Data {
        var result = "HTTP/1.1 \(response.statusCode) \(response.statusMessage)\r\n"

        var headers = response.headers
        // Add Content-Length if not present
        if !headers.contains(where: { $0.name.lowercased() == "content-length" }) {
            headers.append((name: "Content-Length", value: "\(response.body.count)"))
        }

        for header in headers {
            result += "\(header.name): \(header.value)\r\n"
        }
        result += "\r\n"

        var data = Data(result.utf8)
        data.append(response.body)
        return data
    }

    // MARK: - Convenience Builders

    public static func okResponse(body: Data, contentType: String) -> HTTPResponse {
        HTTPResponse(
            statusCode: 200,
            statusMessage: "OK",
            headers: [
                (name: "Content-Type", value: contentType),
            ],
            body: body
        )
    }

    public static func errorResponse(status: Int, message: String) -> HTTPResponse {
        HTTPResponse(
            statusCode: status,
            statusMessage: message,
            headers: [],
            body: Data()
        )
    }

    public static func noContentResponse() -> HTTPResponse {
        HTTPResponse(statusCode: 204, statusMessage: "No Content")
    }
}
