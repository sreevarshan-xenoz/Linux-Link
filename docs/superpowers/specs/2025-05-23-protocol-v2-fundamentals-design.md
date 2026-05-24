# Design Doc: Protocol v2 Fundamentals

## 1. Overview
This design covers the core data structures and framing for the Linux Link v2 protocol, which uses a single multiplexed QUIC connection.

## 2. Architecture
The v2 protocol will be implemented in a new module `core/src/protocol/v2.rs`. It will leverage `quinn` for QUIC transport and `serde`/`serde_json` for serialization.

## 3. Components

### 3.1 Constants & Enums
- `ALPN_V2`: `b"linux-link-v2"`
- `ChannelKind`:
    - `Control = 0`
    - `Video = 1`
    - `Audio = 2`
    - `Input = 3`
    - `File = 4`

### 3.2 Identity Packet
`IdentityPacketV2` will contain:
- `device_id: String`
- `device_name: String`
- `min_version: u32`
- `max_version: u32`
- `capabilities: Vec<String>`

### 3.3 Framing
- `write_framed_json<T: Serialize>(send: &mut quinn::SendStream, data: &T)`
    - Serialize `data` to JSON.
    - Write 4-byte BE length of JSON.
    - Write JSON bytes.
- `read_framed_json<T: DeserializeOwned>(recv: &mut quinn::RecvStream)`
    - Read 4-byte BE length.
    - Read N bytes of JSON.
    - Deserialize JSON to `T`.

## 4. Data Flow
1. Establishment of QUIC connection with `ALPN_V2`.
2. Handshake on Stream 0 (Control) using `IdentityPacketV2`.
3. Subsequent control messages using framed JSON.

## 5. Error Handling
- Use `core::error::Result`.
- Map `serde_json` errors to `LinuxLinkError::Serialization`.
- Map `quinn` errors to `LinuxLinkError::QuicError`.

## 6. Testing Strategy
- Unit tests in `v2.rs`.
- Mocking `quinn::SendStream` and `quinn::RecvStream` behavior if possible, or using a local QUIC connection for integration-style unit tests.
- Verify BE length encoding/decoding.
- Verify large and small JSON payloads.
