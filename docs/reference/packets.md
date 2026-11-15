# Packets and frames

## Contents

### Functions

- [`quic_initial_install`](#function-quic_initial_install): installs the Initial keys of a connection.
- [`quic_cid_put`](#function-quic_cid_put): stores a connection ID.
- [`quic_on_datagram`](#function-quic_on_datagram): handles a received datagram.
- [`quic_accept`](#function-quic_accept): accepts a new server connection.
- [`quic_send_vn`](#function-quic_send_vn): sends Version Negotiation.
- [`quic_on_vn`](#function-quic_on_vn): handles Version Negotiation.
- [`quic_on_retry`](#function-quic_on_retry): handles a Retry.
- [`quic_packet_in`](#function-quic_packet_in): handles one packet.
- [`quic_try_open`](#function-quic_try_open): tries to open the packet being read.
- [`quic_frames`](#function-quic_frames): handles the frames of a packet.
- [`quic_v2`](#function-quic_v2): reads two varints.
- [`quic_v3`](#function-quic_v3): reads three varints.
- [`quic_frame_ack`](#function-quic_frame_ack): handles an ACK frame.
- [`quic_frame_stream`](#function-quic_frame_stream): handles a STREAM frame.
- [`quic_frame_close`](#function-quic_frame_close): handles a CONNECTION_CLOSE frame.
- [`quic_frame_new_cid`](#function-quic_frame_new_cid): handles a NEW_CONNECTION_ID frame.
- [`quic_on_crypto`](#function-quic_on_crypto): handles CRYPTO data.
- [`quic_crx_touches`](#function-quic_crx_touches): tells whether a range touches received CRYPTO data.
- [`quic_conn_output`](#function-quic_conn_output): sends the datagrams of a connection.
- [`quic_datagram`](#function-quic_datagram): builds a datagram.
- [`quic_packet_finish`](#function-quic_packet_finish): protects and records a built packet.
- [`quic_packet_build`](#function-quic_packet_build): builds one packet.
- [`quic_may_elicit`](#function-quic_may_elicit): tells whether an ack-eliciting frame may go in the packet.
- [`quic_elicit`](#function-quic_elicit): marks the packet ack-eliciting and in flight.
- [`quic_add_ref`](#function-quic_add_ref): adds a frame ref to the packet.
- [`quic_frames_out`](#function-quic_frames_out): writes the frames of a packet.
- [`quic_ack_frame`](#function-quic_ack_frame): writes an ACK frame.
- [`quic_app_pending`](#function-quic_app_pending): tells whether the Application space has frames to send other than ACK.
- [`quic_app_frames`](#function-quic_app_frames): writes the Application frames other than ACK, CRYPTO and PING.
- [`quic_stream_out`](#function-quic_stream_out): writes the frames of one stream.
- [`quic_stream_ref`](#function-quic_stream_ref): adds a frame ref of the stream.
- [`quic_stream_frame`](#function-quic_stream_frame): writes one STREAM frame.
- [`quic_stream_read`](#function-quic_stream_read): copies queued bytes of a stream.

## Spec

- Document: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000).
- Section: 6 (version negotiation), 12 (packets and frames), 13 (packetization), 14 (datagram size), 17 (packet formats), 19 (frame types).

## Function `quic_initial_install`

Installs the Initial keys of a connection.

### Signature

```
quic_initial_install(dcid)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dcid` | input | [`ConnectionId`](packet-protection.md#type-connectionid) |

### Function does

- Derives the Initial keys and gives each direction its role.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 192 bytes on x86-64 (return address included), 192 bytes on ARM64, 208 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_initial_install`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `dcid`.

## Function `quic_cid_put`

Stores a connection ID.

### Signature

```
quic_cid_put(cid, p, n)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `cid` | output | [`ConnectionId`](packet-protection.md#type-connectionid) |
| `p` | input | `n` bytes |
| `n` | input | u64, at most 20 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_cid_put`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `cid`, `p`, `n`.

## Function `quic_on_datagram`

Handles each packet of a received datagram in turn (RFC 9000 section 12.2).

### Signature

```
quic_on_datagram(event)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `event` | input | [`DatagramEvent`](node.md#type-datagramevent) |

### Function does

- Takes long headers until a short one, which takes the rest.
- Finds the connection by our connection ID, or by the first ID of the client.
- Accepts a new connection for the first Initial of a client, sends Version Negotiation for another version, and drops the rest.
- Counts the bytes received for the amplification limit.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 176 bytes on x86-64 (return address included), 176 bytes on ARM64, 192 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_datagram`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `event`.

## Function `quic_accept`

Accepts a new server connection.

### Signature

```
quic_accept(header) -> conn
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `header` | input | the header fields of `quic_on_datagram` |

### Function does

- Requires a node that accepts, a datagram of at least 1200 bytes, a Destination Connection ID of at least 8 bytes, and a free slot.
- Returns the new connection, or 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_accept`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- ARM64 and RISC-V read the event in x23 or s5; x86-64 takes it as a second argument.
- Argument order: `header`.

## Function `quic_send_vn`

Sends a Version Negotiation packet back to a client that offered another version (RFC 9000 section 6.1).

### Signature

```
quic_send_vn(header)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `header` | input | the header fields of `quic_on_datagram` |

### Function does

- Swaps the connection IDs.
- Lists version 1 only.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_send_vn`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- ARM64 and RISC-V read the event in x23 or s5; x86-64 takes it as a second argument.
- Argument order: `header`.

## Function `quic_on_vn`

Handles Version Negotiation for a client before any packet of the server (RFC 9000 section 6.2).

### Signature

```
quic_on_vn(p, end)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the version list |
| `end` | input | its end |

### Function does

- Fails the dial with `QUIC_ERR_VERSION` when the list does not hold version 1.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_vn`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `p`, `end`.

## Function `quic_on_retry`

Handles a Retry for a client before any other packet of the server, once (RFC 9000 section 17.2.5).

### Signature

```
quic_on_retry(packet, n, scid, scid_len)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `packet` | input | `n` bytes |
| `n` | input | u64 |
| `scid` | input | `scid_len` bytes |
| `scid_len` | input | u64 |

### Function does

- Checks the integrity tag.
- Takes the connection ID of the server and the token.
- Changes the Initial keys and sends the ClientHello again.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 192 bytes on x86-64 (return address included), 192 bytes on ARM64, 208 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_retry`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `packet`, `n`, `scid`, `scid_len`.

## Function `quic_packet_in`

Handles one packet.

### Signature

```
quic_packet_in(conn, space, packet, pn_offset, n)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `conn` | input | a connection slot |
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |
| `packet` | input | `n` bytes |
| `pn_offset` | input | u64 |
| `n` | input | u64 |

### Function does

- Opens it with the keys of its space, or the next or previous key phase for a 1-RTT packet.
- Checks the reserved bits.
- Records its packet number and handles its frames.
- Drops a packet that does not open; a 1-RTT one may be a stateless reset.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_packet_in`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `conn`, `space`, `packet`, `pn_offset`, `n`.

## Function `quic_try_open`

Tries to open the packet being read.

### Signature

```
quic_try_open(keys) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `keys` | input | [`PacketKeys`](packet-protection.md#type-packetkeys) |

### Function does

- Copies the packet to the packet buffer of the scratch and opens it there, the result in the scratch.
- Returns 0, or the error; the buffer then holds the first byte without header protection.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_try_open`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- ARM64 and RISC-V read the packet in x21 or s3, the packet number offset in x22 or s4, the length in x23 or s5 and the space record in x24 or s6.
- x86-64 takes the length and the space record as the arguments rsi and rdx, and reads the packet in r12 and the packet number offset in r13.
- Argument order: `keys`.

## Function `quic_frames`

Handles the frames of a packet in order (RFC 9000 section 19).

### Signature

```
quic_frames(p, n, space) -> (result, eliciting)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | `n` bytes |
| `n` | input | u64 |
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |

### Function does

- Takes PADDING, PING, ACK, CRYPTO and CONNECTION_CLOSE only in Initial and Handshake packets (RFC 9000 section 12.4).
- Returns 0, -1 after a CONNECTION_CLOSE, or the error code; and 1 when the packet is ack-eliciting.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_frames`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- It returns two values: x0, rax or a0, then x1, rdx or a1.
- Argument order: `p`, `n`, `space`.

## Function `quic_v2`

Reads two varints.

### Signature

```
quic_v2(p, end) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the varints |
| `end` | input | their end |

### Function does

- Puts their values in the scratch, and returns the position after them, or 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_v2`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `p`, `end`.

## Function `quic_v3`

Reads three varints.

### Signature

```
quic_v3(p, end) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the varints |
| `end` | input | their end |

### Function does

- Puts their values in the scratch, and returns the position after them, or 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_v3`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `p`, `end`.

## Function `quic_frame_ack`

Handles an ACK frame.

### Signature

```
quic_frame_ack(p, end, space, type) -> (next, error)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the frame after its type |
| `end` | input | the end of the packet |
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |
| `type` | input | u64: 0x02 or 0x03 |

### Function does

- Hands at most 64 ranges to `quic_on_ack`.
- Returns PROTOCOL_VIOLATION for an ACK of a packet number never sent.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_frame_ack`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- It returns two values: x0, rax or a0, then x1, rdx or a1.
- Argument order: `p`, `end`, `space`, `type`.

## Function `quic_frame_stream`

Handles a STREAM frame.

### Signature

```
quic_frame_stream(p, end, type) -> (next, error)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the frame after its type |
| `end` | input | the end of the packet |
| `type` | input | u64: 0x08 to 0x0f |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_frame_stream`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- It returns two values: x0, rax or a0, then x1, rdx or a1.
- Argument order: `p`, `end`, `type`.

## Function `quic_frame_close`

Handles a CONNECTION_CLOSE frame.

### Signature

```
quic_frame_close(p, end, type) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the frame after its type |
| `end` | input | the end of the packet |
| `type` | input | u64: 0x1c or 0x1d |

### Function does

- Drains the connection; the application hears the code.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_frame_close`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `p`, `end`, `type`.

## Function `quic_frame_new_cid`

Handles a NEW_CONNECTION_ID frame.

### Signature

```
quic_frame_new_cid(p, end) -> (next, error)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the frame after its type |
| `end` | input | the end of the packet |

### Function does

- Keeps the connection ID in use and one spare (active_connection_id_limit 2).
- Moves to the spare and retires the old one when retire_prior_to asks.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_frame_new_cid`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- It returns two values: x0, rax or a0, then x1, rdx or a1.
- Argument order: `p`, `end`.

## Function `quic_on_crypto`

Handles CRYPTO data.

### Signature

```
quic_on_crypto(space, offset, data, len) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |
| `offset` | input | u64 |
| `data` | input | `len` bytes |
| `len` | input | u64 |

### Function does

- Adds the data to the receive block of the space: at most 4 separate ranges in 4080 bytes.
- Hands the complete messages to TLS (`quic_tls_feed`).
- Returns 0, CRYPTO_BUFFER_EXCEEDED, INTERNAL_ERROR, or the error of `quic_tls_feed`.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_crypto`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `space`, `offset`, `data`, `len`.

## Function `quic_crx_touches`

Tells whether a range touches received CRYPTO data.

### Signature

```
quic_crx_touches(space, start, end) -> touches
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | the space record |
| `start` | input | u64 |
| `end` | input | u64 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_crx_touches`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `space`, `start`, `end`.

## Function `quic_conn_output`

Sends the datagrams of a connection.

### Signature

```
quic_conn_output()
```

### Function does

- Builds datagrams while the action room, the amplification limit and something to send allow.
- Adds one SEND action for each.
- A server sends at most 3 times the bytes it received until the address is validated.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_conn_output`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.

## Function `quic_datagram`

Builds a datagram.

### Signature

```
quic_datagram(buf, max) -> bytes
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `buf` | output | `max` bytes |
| `max` | input | u64 |

### Function does

- Builds a packet for each space that has something to send, Initial first.
- Pads to 1200 bytes a datagram with an Initial packet of a client, or an ack-eliciting one of a server (RFC 9000 section 14.1).
- Protects and records each packet.
- Returns the bytes, or 0 when there is nothing to send.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 576 bytes on x86-64 (return address included), 576 bytes on ARM64, 592 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_datagram`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `buf`, `max`.

## Function `quic_packet_finish`

Protects and records a built packet.

### Signature

```
quic_packet_finish(packet)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `packet` | input | the packet fields |

### Function does

- Writes the Length of a long header.
- Protects the packet.
- Records an ack-eliciting or padded packet.
- A client discards its Initial keys when it sends its first Handshake packet (RFC 9001 section 4.9.1).

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_packet_finish`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `packet`.

## Function `quic_packet_build`

Builds one packet.

### Signature

```
quic_packet_build(space, dst, room, packet) -> built
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |
| `dst` | output | `room` bytes |
| `room` | input | u64 |
| `packet` | output | the packet fields |

### Function does

- Writes the header with a 4-byte packet number, then the frames, leaving room for the tag.
- Returns 1 when the packet holds a frame, else 0 and nothing is kept.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_packet_build`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- x86-64 keeps the packet in the SC_PACKET scratch word and its space record in SC_SPREC for the functions it calls.
- Argument order: `space`, `dst`, `room`, `packet`.

## Function `quic_may_elicit`

Tells whether an ack-eliciting frame may go in the packet.

### Signature

```
quic_may_elicit(needs_ref) -> allowed
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `needs_ref` | input | u64: 1 when the frame needs a frame ref |

### Function does

- Requires a free record and, when needed, a free frame ref.
- Requires room in the congestion window, or a probe due in the space.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_may_elicit`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1; the packet being built in x23, the SC_PACKET scratch word, s5; its space record in x26, the SC_SPREC scratch word, s8.
- Argument order: `needs_ref`.

## Function `quic_elicit`

Marks the packet ack-eliciting and in flight.

### Signature

```
quic_elicit()
```

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_elicit`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the packet being built in x23, the SC_PACKET scratch word, s5.

## Function `quic_add_ref`

Adds a frame ref to the packet.

### Signature

```
quic_add_ref(kind, flags, slot_gen, value, offset_len)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `kind` | input | u64: a byte |
| `flags` | input | u64: a byte |
| `slot_gen` | input | u64: the generation, 16 bits |
| `value` | input | u64: the slot or a value, 32 bits |
| `offset_len` | input | u64 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_add_ref`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the packet being built in x23, the SC_PACKET scratch word, s5.
- Argument order: `kind`, `flags`, `slot_gen`, `value`, `offset_len`.

## Function `quic_frames_out`

Writes the frames of a packet.

### Signature

```
quic_frames_out(p, end) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | output | the frames |
| `end` | input | the end of the room |

### Function does

- Writes ACK; CONNECTION_CLOSE alone when closing; CRYPTO.
- Writes in the Application space HANDSHAKE_DONE, PATH_RESPONSE, RETIRE_CONNECTION_ID, MAX_DATA, MAX_STREAMS and the stream frames.
- Writes PING for a probe or a keep-alive.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_frames_out`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1; the space in x20, rbp, s2; the packet being built in x23, the SC_PACKET scratch word, s5; its space record in x26, the SC_SPREC scratch word, s8.
- Argument order: `p`, `end`.

## Function `quic_ack_frame`

Writes an ACK frame.

### Signature

```
quic_ack_frame(p, end) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | output | the frame |
| `end` | input | the end of the room |

### Function does

- Writes the received ranges of the space, as many as fit.
- Writes the delay in units of 8 microseconds (ack_delay_exponent 3) in the Application space.
- Returns 0 when no range fits.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_ack_frame`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1; the space in x20, rbp, s2; its space record in x26, the SC_SPREC scratch word, s8.
- Argument order: `p`, `end`.

## Function `quic_app_pending`

Tells whether the Application space has frames to send other than ACK.

### Signature

```
quic_app_pending() -> pending
```

### Function does

- Lets an ACK not yet due go with them.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_app_pending`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.

## Function `quic_app_frames`

Writes the Application frames other than ACK, CRYPTO and PING.

### Signature

```
quic_app_frames() -> next
```

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_app_frames`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1; the position in x21, r12, s3; the end of the room in x22, r13, s4; the packet being built in x23, the SC_PACKET scratch word, s5; its space record in x26, the SC_SPREC scratch word, s8.

## Function `quic_stream_out`

Writes the frames of one stream.

### Signature

```
quic_stream_out(stream) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `stream` | input | a stream slot |

### Function does

- Writes RESET_STREAM, STOP_SENDING and MAX_STREAM_DATA.
- Writes STREAM frames: lost ranges first, then new bytes within the flow control limits.
- Adds the FIN with the last byte.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_out`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1; the position in x21, r12, s3; the end of the room in x22, r13, s4; the packet being built in x23, the SC_PACKET scratch word, s5; its space record in x26, the SC_SPREC scratch word, s8.
- x86-64 keeps the stream slot in the SC_SLOT scratch word for the functions it calls.
- Argument order: `stream`.

## Function `quic_stream_ref`

Adds a frame ref of the stream.

### Signature

```
quic_stream_ref(kind)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `kind` | input | u64 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_ref`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the stream in x20, rbp, s2; the stream slot in x25, the SC_SLOT scratch word, s7; the packet being built in x23, the SC_PACKET scratch word, s5.
- Argument order: `kind`.

## Function `quic_stream_frame`

Writes one STREAM frame.

### Signature

```
quic_stream_frame(offset, fin, n) -> (bytes, next)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `offset` | input | u64 |
| `fin` | input | u64: 1 to send the FIN with the last byte |
| `n` | input | u64 |

### Function does

- Puts as many of the n bytes as fit, with the FIN when fin is 1 and all fit.
- Returns the bytes put, or -1 when no frame fits; and the position after.
- A frame of 0 bytes with the FIN counts.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 128 bytes on x86-64 (return address included), 128 bytes on ARM64, 144 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_frame`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the stream in x20, rbp, s2; the position in x21, r12, s3; the end of the room in x22, r13, s4; the packet being built in x23, the SC_PACKET scratch word, s5; its space record in x26, the SC_SPREC scratch word, s8; the stream slot in x25, the SC_SLOT scratch word, s7.
- It returns two values: x0, rax or a0, then x1, rdx or a1.
- Argument order: `offset`, `fin`, `n`.

## Function `quic_stream_read`

Copies queued bytes of a stream.

### Signature

```
quic_stream_read(dst, offset, n)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | `n` bytes |
| `offset` | input | u64 |
| `n` | input | u64 |

### Function does

- Copies across chunks.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_read`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the stream in x20, rbp, s2.
- Argument order: `dst`, `offset`, `n`.

## Test vectors

- Scenarios
  - File: [tests/runner/runner.c](../../tests/runner/runner.c): every scenario; garbage sends malformed datagrams.
- transport-interop of libp2p/test-plans
  - File: [tests/interop/](../../tests/interop/).

## Results

<!-- CI generates the tick table for each function here. -->
