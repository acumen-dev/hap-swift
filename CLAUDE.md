# hap-swift

## What this is

A native Swift implementation of the [HomeKit Accessory Protocol (HAP)](https://developer.apple.com/homekit/) — the TCP-based protocol Apple Home uses for SecuritySystem, GarageDoorOpener, and other device types that Matter does not support.

**Why it exists**: The Acumen bridge system exposes security panels and garage doors to Apple Home. Matter (spec 1.0–1.5) has no SecuritySystem or GarageDoorOpener device type — these come from HAP, not Matter. This library lets Acumen advertise HAP accessories alongside Matter devices on the same network.

**Relationship to other packages**:
- `acumen-dev/mdns-swift` — shared mDNS/DNS-SD discovery used by both this package and matter-swift. HAP advertises as `_hap._tcp`.
- `acumen-dev/matter-swift` — separate library; HAP and Matter are unrelated protocols that happen to use the same discovery layer.

---

## Module Architecture

```
HAPCore          — HAP types, TLV8, constants, service/characteristic definitions
    ↑
HAPCrypto        — SRP-6a (3072-bit), Curve25519, ChaCha20-Poly1305, HKDF-SHA512
    ↑
HAPTransport     — TCP server, pairing state machine, encrypted sessions, characteristic protocol
    ↑
├── HAPApple     — Network.framework TCP + MDNSApple  (Apple platforms)
└── HAPLinux     — SwiftNIO TCP + MDNSLinux            (Linux)

HAPSwift         — Umbrella re-export
```

### Module responsibilities

**HAPCore** — Zero external dependencies.
- `TLV8` encoder/decoder (type: UInt8, length: UInt8 max 255, value: Data; fragmented for >255 bytes)
- `HAPServiceType` and `HAPCharacteristicType` — `ServiceType`-style structs with static extensions for known types
- `HAPCategory` enum (SecuritySystem = 11, GarageDoorOpener = 2, Bridge = 2, etc.)
- `HAPStatus` error codes
- `AccessoryInfo` — name, model, manufacturer, serial, firmware version
- `HAPCharacteristic` and `HAPService` value types
- `HAPAccessory` — the top-level accessory model

**HAPCrypto** — Depends on `swift-crypto`.
- SRP-6a with HAP's 3072-bit prime (see §5.5 of HAP spec)
- `Ed25519` long-term pairing keys (via `swift-crypto` `Curve25519.Signing`)
- `Curve25519` ephemeral ECDH keys (via `Curve25519.KeyAgreement`)
- `ChaCha20Poly1305` encryption/decryption for HAP frames
- `HKDF` key derivation (SHA-512) for session keys and pairing sub-keys
- Pairing storage protocol (`PairingStore`) — persists controller long-term public keys

**HAPTransport** — Depends on `HAPCore`, `HAPCrypto`, `MDNSCore`.
- `HAPServer` protocol — start/stop, delegate callbacks
- `HAPSession` — per-connection encrypted state, read/write counters
- `PairingStateMachine` — drives M1→M6 pairing exchange
- `CharacteristicProtocol` — HTTP-like framing over TCP (GET /accessories, PUT /characteristics, etc.)
- `HAPAdvertiser` — wraps `ServiceDiscovery` to advertise `_hap._tcp` with correct TXT records
- `HAPBridge` — multi-accessory bridge (AID assignment, accessory database)

**HAPApple / HAPLinux** — Platform TCP implementations.
- `TCPServer` that accepts connections and creates `HAPSession` per connection
- Uses `NWListener` (Apple) or SwiftNIO `ServerBootstrap` (Linux)

---

## HAP Protocol Reference

### mDNS Advertisement

Service type: `_hap._tcp`

Required TXT records:

| Key | Meaning | Example |
|-----|---------|---------|
| `c#` | Config number — increment on accessory DB change | `"1"` |
| `ff` | Feature flags — `0x01` = supports HAP pairing | `"0"` |
| `id` | Device ID — colon-separated MAC-style hex | `"AA:BB:CC:DD:EE:FF"` |
| `md` | Model name | `"AcumenBridge"` |
| `pv` | Pairing protocol version | `"1.1"` |
| `s#` | State number (always `"1"` for accessories) | `"1"` |
| `sf` | Status flags — `0x01` = not paired, `0x00` = paired | `"1"` |
| `ci` | Category identifier | `"2"` (bridge) |

### TLV8 Encoding

HAP uses TLV8 (not Matter TLV) throughout pairing and characteristic encoding.

```
┌──────┬────────┬───────────────┐
│ type │ length │ value         │
│  1B  │   1B   │ 0–255 bytes   │
└──────┴────────┴───────────────┘
```

Values longer than 255 bytes are fragmented: send the same type with length=255, then continue with the same type and the remainder. A separator (type=0xFF, length=0) appears between TLV items of the same type in a sequence.

### Pairing (§5.6 HAP spec)

Six-message SRP exchange. All messages are TLV8-encoded over the HTTP-like TCP protocol.

```
iOS → Accessory  POST /pair-setup   M1: kTLVType_State=1, kTLVType_Method=0
Accessory → iOS                     M2: State=2, PublicKey (SRP B), Salt
iOS → Accessory                     M3: State=3, PublicKey (SRP A), Proof (SRP M1)
Accessory → iOS                     M4: State=4, Proof (SRP M2)
iOS → Accessory                     M5: State=5, EncryptedData (Ed25519 key exchange, encrypted with session key)
Accessory → iOS                     M6: State=6, EncryptedData (accessory Ed25519 public key, signed)
```

SRP parameters:
- Group: RFC 5054 3072-bit (same prime N as in HAP spec appendix)
- Hash: SHA-512
- Username: `"Pair-Setup"`
- Password: the 8-digit setup code (e.g. `"031-45-154"` formatted without dashes as `"03145154"`)

Key derivation for M5/M6 (HKDF-SHA512):
- Salt: `"Pair-Setup-Encrypt-Salt"`
- Info: `"Pair-Setup-Encrypt-Info"`
- Key length: 32 bytes
- Nonce for M5: `"PS-Msg05"`, for M6: `"PS-Msg06"`

### Session Encryption (§6.5 HAP spec)

After pairing, all HAP frames are encrypted with ChaCha20-Poly1305.

```
┌──────────────┬───────────────────────────────────────┐
│ length (2B LE)│ encrypted payload + 16-byte auth tag  │
└──────────────┴───────────────────────────────────────┘
```

- Nonce: 12 bytes — first 4 bytes zero, last 8 bytes = little-endian frame counter
- Frame counter increments separately for each direction (read/write)
- Session keys derived with HKDF from the SRP shared secret:
  - AccessoryToController: salt `"Control-Salt"`, info `"Control-Write-Encryption-Key"`
  - ControllerToAccessory: salt `"Control-Salt"`, info `"Control-Read-Encryption-Key"`

### Characteristic HTTP Protocol

HAP uses HTTP/1.1-style framing over the encrypted TCP connection.

Key endpoints:

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/accessories` | Full accessory/service/characteristic list |
| `PUT` | `/characteristics` | Write characteristic values |
| `GET` | `/characteristics?id=1.10,1.11` | Read specific characteristics |
| `PUT` | `/characteristics` with `ev=true` | Subscribe to characteristic events |
| `POST` | `/pair-setup` | Pairing (unauthenticated) |
| `POST` | `/pair-verify` | Session establishment (post-pairing) |

### Accessory IDs

- Each accessory has an **AID** (Accessory ID) — assigned by the bridge, starts at 1
- Each characteristic has an **IID** (Instance ID) — unique within the accessory, starts at 1
- The bridge's own Accessory Information service is AID=1

---

## Target Accessories

### SecuritySystem (Category 11)

Services:
1. **Accessory Information** (required on all accessories): Name, Manufacturer, Model, SerialNumber, FirmwareRevision, Identify
2. **SecuritySystem**:
   - `CurrentSecuritySystemState` (read, notify): 0=StayArm, 1=AwayArm, 2=NightArm, 3=Disarmed, 4=AlarmTriggered
   - `TargetSecuritySystemState` (read, write, notify): 0=StayArm, 1=AwayArm, 2=NightArm, 3=Disarmed
   - `SecuritySystemAlarmType` (optional, read, notify): 0=NoAlarm, 1=Unknown

Mapping to Acumen: Disarmed=3, StayArm=0 (Home), AwayArm=1 (Away), NightArm=2 (Night/Sleep).

### GarageDoorOpener (Category 2)

Services:
1. **Accessory Information**
2. **GarageDoorOpener**:
   - `CurrentDoorState` (read, notify): 0=Open, 1=Closed, 2=Opening, 3=Closing, 4=Stopped
   - `TargetDoorState` (read, write, notify): 0=Open, 1=Closed
   - `ObstructionDetected` (read, notify): Bool

---

## Code Conventions

These apply to every file in this repository.

### Copyright header (non-negotiable)
```swift
// FileName.swift
// Copyright 2026 Monagle Pty Ltd
```

### Section markers
```swift
// MARK: - Section Name
```

### Concurrency
- **Swift 6.1 strict concurrency** — all types must be `Sendable` or actor-isolated
- Use `actor` for any type with mutable state shared across tasks
- Use `@unchecked Sendable` only for types protected by an explicit lock (document the lock)
- Never use `nonisolated(unsafe)` without a clear thread-safety argument

### Access levels
- `public` for all API types and methods
- `internal` / `private` for implementation details
- No `open` (no subclassing intended)

### Imports
- Explicit imports only — no `import Foundation` unless Foundation types are actually used
- Platform-conditional imports wrapped in `#if canImport(Network)` etc.

### Error types
- Define `public enum HAPError: Error, Sendable` in `HAPCore`
- Each module may add its own error type (e.g. `HAPCryptoError`, `HAPPairingError`)

### Swift Testing
```swift
import Testing
@testable import ModuleName

@Suite("FeatureName Tests")
struct FeatureNameTests {
    @Test("description")
    func specificBehaviour() async throws {
        // arrange / act / assert
    }
}
```

---

## Build & Test

```bash
swift build                          # all targets
swift build --target HAPCore         # single target
swift test                           # all tests
swift test --filter HAPCryptoTests   # single suite
```

CI runs on macOS-15 and Linux (`swift:6.2-noble` Docker) on every push to `main` and on PRs.

---

## What NOT to do

- Don't add docstrings to code you didn't write
- Don't add error handling for impossible cases
- Don't create abstractions for one-off operations
- Don't add features beyond what was asked
- Don't use `--no-verify` to hide build failures
- Don't implement TCP transport before the pairing/crypto layer is solid — get `HAPCrypto` tests passing with known SRP vectors first
