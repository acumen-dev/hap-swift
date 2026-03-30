// HTTPProtocolTests.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Testing
@testable import HAPTransport

@Suite("HTTPProtocol Tests")
struct HTTPProtocolTests {

    @Test("parse GET request")
    func parseGetRequest() {
        let raw = "GET /accessories HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n"
        let request = HTTPProtocol.parseRequest(from: Data(raw.utf8))
        #expect(request != nil)
        #expect(request?.method == "GET")
        #expect(request?.path == "/accessories")
    }

    @Test("parse POST request with body")
    func parsePostRequest() {
        let raw = "POST /pair-setup HTTP/1.1\r\nContent-Type: application/pairing+tlv8\r\nContent-Length: 3\r\n\r\nABC"
        let request = HTTPProtocol.parseRequest(from: Data(raw.utf8))
        #expect(request != nil)
        #expect(request?.method == "POST")
        #expect(request?.path == "/pair-setup")
        #expect(request?.body == Data("ABC".utf8))
    }

    @Test("parse PUT request")
    func parsePutRequest() {
        let raw = "PUT /characteristics HTTP/1.1\r\nContent-Type: application/hap+json\r\n\r\n{}"
        let request = HTTPProtocol.parseRequest(from: Data(raw.utf8))
        #expect(request?.method == "PUT")
        #expect(request?.path == "/characteristics")
    }

    @Test("parse request with query string")
    func parseRequestWithQuery() {
        let raw = "GET /characteristics?id=1.10,1.11 HTTP/1.1\r\n\r\n"
        let request = HTTPProtocol.parseRequest(from: Data(raw.utf8))
        #expect(request?.path == "/characteristics?id=1.10,1.11")
    }

    @Test("serialize response")
    func serializeResponse() {
        let response = HTTPResponse(
            statusCode: 200,
            statusMessage: "OK",
            headers: [(name: "Content-Type", value: "application/hap+json")],
            body: Data("{}".utf8)
        )
        let data = HTTPProtocol.serializeResponse(response)
        let string = String(data: data, encoding: .utf8)!
        #expect(string.hasPrefix("HTTP/1.1 200 OK\r\n"))
        #expect(string.contains("Content-Type: application/hap+json"))
        #expect(string.contains("Content-Length: 2"))
        #expect(string.hasSuffix("{}"))
    }

    @Test("content type constants")
    func contentTypes() {
        #expect(HTTPProtocol.hapJSON == "application/hap+json")
        #expect(HTTPProtocol.pairingTLV8 == "application/pairing+tlv8")
    }

    @Test("ok response helper")
    func okResponse() {
        let response = HTTPProtocol.okResponse(body: Data("test".utf8), contentType: "text/plain")
        #expect(response.statusCode == 200)
        #expect(response.body == Data("test".utf8))
        #expect(response.headers.first?.value == "text/plain")
    }

    @Test("error response helper")
    func errorResponseHelper() {
        let response = HTTPProtocol.errorResponse(status: 404, message: "Not Found")
        #expect(response.statusCode == 404)
        #expect(response.body.isEmpty)
    }
}
