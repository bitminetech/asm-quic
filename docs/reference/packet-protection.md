# Packet protection

## Contents

### Functions

- [`quic_initial_keys`](#function-quic_initial_keys): derives the Initial keys of a connection ID.
- [`quic_packet_seal`](#function-quic_packet_seal): protects a packet.
- [`quic_packet_open`](#function-quic_packet_open): removes the protection of a packet.
- [`quic_retry_tag`](#function-quic_retry_tag): computes the integrity tag of a Retry packet.
- [`quic_expand_label`](#function-quic_expand_label): derives bytes with HKDF-Expand-Label.
- [`quic_derive_keys`](#function-quic_derive_keys): derives packet keys from a traffic secret.
- [`quic_initial_derive`](#function-quic_initial_derive): derives the Initial keys of a checked connection ID.
- [`quic_nonce`](#function-quic_nonce): builds the AEAD nonce of a packet.
- [`quic_hp_mask`](#function-quic_hp_mask): computes a header protection mask.
- [`quic_pn_decode`](#function-quic_pn_decode): decodes a packet number.
- [`quic_mask_header`](#function-quic_mask_header): applies a header protection mask.
- [`quic_seal`](#function-quic_seal): protects a packet in place.
- [`quic_open`](#function-quic_open): opens a packet in place.

### Types

- [`ConnectionId`](#type-connectionid): a QUIC connection ID of 0 to 20 bytes.
- [`PacketKeys`](#type-packetkeys): the keys of one direction of a packet number space.
- [`InitialKeys`](#type-initialkeys): the Initial keys of both directions.
- [`PlainPacket`](#type-plainpacket): a packet to protect: its number, its header and its frames.
- [`OpenRequest`](#type-openrequest): a protected packet to open.
- [`OpenedPacket`](#type-openedpacket): an opened packet: its number, its header and its frames.
- [`PacketScratch`](#type-packetscratch): the work area of `quic_packet_seal` and `quic_packet_open`.

### Constants

- `QUIC_PACKET_SCRATCH`: bytes of a PacketScratch: 5208.
- `QUIC_MAX_PACKET`: the largest Retry packet `quic_retry_tag` takes: 1500 bytes.

## Spec

- Document: [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001), QUIC-TLS.
- Section: 5 (packet protection), with the varint and packet number rules of RFC 9000 section 16 and appendix A.3.

## Function `quic_initial_keys`

Derives the client and server Initial keys of a Destination Connection ID (RFC 9001 section 5.2).

### Signature

```
quic_initial_keys(dcid, keys) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dcid` | input | [`ConnectionId`](#type-connectionid) |
| `keys` | output | [`InitialKeys`](#type-initialkeys) |

### Returns

- `QUIC_OK`: `keys` holds the client keys, then the server keys.
- `QUIC_INVALID_ARGUMENT`: The length of `dcid` is above 20.

### Function does

- Takes initial_secret = HKDF-Extract(initial_salt of QUIC version 1, the ID bytes).
- Takes the client and server secrets with HKDF-Expand-Label "client in" and "server in", 32 bytes each.
- Derives the key, IV and header protection key of each secret (`quic_derive_keys`).

### Function never

- Writes outside `keys` and its own stack.
- Makes an OS call.

### Limits

- Stack: 2000 bytes on x86-64 (return address included), 1968 bytes on ARM64, 2128 bytes on RISC-V, callees included, the most the test runner measured.

### ABI

- Role: L2.
- Symbol: `quic_initial_keys` (`_quic_initial_keys` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `dcid`, `keys`.

## Function `quic_packet_seal`

Protects a packet: AEAD over the frames, then header protection (RFC 9001 sections 5.3 and 5.4).

### Signature

```
quic_packet_seal(keys, packet, scratch, sealed) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `keys` | input | [`PacketKeys`](#type-packetkeys) |
| `packet` | input | [`PlainPacket`](#type-plainpacket) |
| `scratch` | scratch | [`PacketScratch`](#type-packetscratch) |
| `sealed` | output | [`ByteList`](node.md#type-bytelist): the protected packet |

### Returns

- `QUIC_OK`: `sealed` holds the header, the sealed frames and the 16-byte tag.
- `QUIC_BUFFER_TOO_SMALL`: The scratch is below `QUIC_PACKET_SCRATCH` bytes, or `sealed` has no room for header + payload + 16 bytes.
- `QUIC_INVALID_ARGUMENT`: A ByteList of `packet` lies outside it; the header is empty, above 256 bytes, or shorter than its packet number; the payload is above 1504 bytes; or packet number and payload together are below 4 bytes.

### Function does

- Takes the packet number length from the two low bits of the first header byte.
- Seals the payload with AES-128-GCM: the nonce is the IV XOR the packet number, the header is the associated data.
- Masks the low 4 bits (long header) or 5 bits (short header) of the first byte and the packet number bytes with AES-ECB of the 16-byte sample at 4 bytes after the packet number start.

### Function never

- Writes outside the scratch, `sealed` and its own stack.
- Makes an OS call.

### Limits

- Stack: 1816 bytes on x86-64 (return address included), 1808 bytes on ARM64, 1920 bytes on RISC-V, callees included, the most the test runner measured.

### ABI

- Role: L2.
- Symbol: `quic_packet_seal` (`_quic_packet_seal` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `keys`, `packet`, `scratch`, `sealed`.

## Function `quic_packet_open`

Removes the header protection of a packet, decodes its packet number and decrypts its frames (RFC 9001 sections 5.3 and 5.4).

### Signature

```
quic_packet_open(keys, request, scratch, opened) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `keys` | input | [`PacketKeys`](#type-packetkeys) |
| `request` | input | [`OpenRequest`](#type-openrequest) |
| `scratch` | scratch | [`PacketScratch`](#type-packetscratch) |
| `opened` | output | [`OpenedPacket`](#type-openedpacket) |

### Returns

- `QUIC_OK`: `opened` holds the packet number, the header without protection and the frames.
- `QUIC_BUFFER_TOO_SMALL`: The scratch is below `QUIC_PACKET_SCRATCH` bytes, or `opened` has no room for the packet.
- `QUIC_INVALID_ARGUMENT`: The packet ByteList lies outside `request`.
- `QUIC_INVALID_PACKET`: The packet is above 1776 bytes, its packet number offset is not inside it, it is too short for the sample or the tag, or its header is above 256 bytes.
- `QUIC_DECRYPT_FAILED`: The tag does not match.

### Function does

- Takes the sample at 4 bytes after the packet number offset and removes the header protection.
- Decodes the full packet number from the truncated one and the largest received (RFC 9000 appendix A.3).
- Opens the payload with AES-128-GCM; the frames start at the first multiple of 8 after the header in `opened`.

### Function never

- Writes outside the scratch, `opened` and its own stack.
- Makes an OS call.

### Limits

- Stack: 1816 bytes on x86-64 (return address included), 1808 bytes on ARM64, 1920 bytes on RISC-V, callees included, the most the test runner measured.

### ABI

- Role: L2.
- Symbol: `quic_packet_open` (`_quic_packet_open` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `keys`, `request`, `scratch`, `opened`.

## Function `quic_retry_tag`

Computes the Retry Integrity Tag of a Retry packet (RFC 9001 section 5.8).

### Signature

```
quic_retry_tag(odcid, retry, scratch, tag) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `odcid` | input | [`ConnectionId`](#type-connectionid): the Original Destination Connection ID |
| `retry` | input | [`ByteList`](node.md#type-bytelist): the Retry packet without its tag |
| `scratch` | scratch | u64 size, then room for a ByteList of the pseudo-packet |
| `tag` | output | 16 bytes |

### Returns

- `QUIC_OK`: `tag` holds the tag.
- `QUIC_INVALID_ARGUMENT`: The length of `odcid` is above 20, or the packet is above 1500 bytes.
- `QUIC_BUFFER_TOO_SMALL`: The scratch has no room for the pseudo-packet.

### Function does

- Builds the Retry pseudo-packet: the ODCID length byte, the ODCID, then the packet.
- Seals an empty plaintext with AES-128-GCM under the fixed key and nonce of QUIC version 1, the pseudo-packet as the associated data.

### Function never

- Writes outside the scratch, `tag` and its own stack.
- Makes an OS call.

### Limits

- Stack: 1720 bytes on x86-64 (return address included), 1712 bytes on ARM64, 1792 bytes on RISC-V, callees included, the most the test runner measured.

### ABI

- Role: L2.
- Symbol: `quic_retry_tag` (`_quic_retry_tag` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `odcid`, `retry`, `scratch`, `tag`.

## Function `quic_expand_label`

Computes HKDF-Expand-Label of RFC 8446 section 7.1 with SHA-256.

### Signature

```
quic_expand_label(secret, label, label_len, context, context_len, length, out)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `secret` | input | 32 bytes |
| `label` | input | `label_len` bytes, without "tls13 " |
| `label_len` | input | u64, at most 32 |
| `context` | input | `context_len` bytes |
| `context_len` | input | u64, at most 32 |
| `length` | input | u64, at most 64 |
| `out` | output | `length` bytes |

### Function does

- Takes the secret as the PRK and "tls13 " || label as the label.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 560 bytes on x86-64 (return address included), 560 bytes on ARM64, 576 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_expand_label`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- x86-64: the seventh argument `out` is in r10.
- Argument order: `secret`, `label`, `label_len`, `context`, `context_len`, `length`, `out`.

## Function `quic_derive_keys`

Derives the AEAD key, IV and header protection key of a 32-byte traffic secret (RFC 9001 section 5.1).

### Signature

```
quic_derive_keys(secret, keys)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `secret` | input | 32 bytes |
| `keys` | output | [`PacketKeys`](#type-packetkeys) |

### Function does

- Uses the labels "quic key" (16 bytes), "quic iv" (12 bytes) and "quic hp" (16 bytes).

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_derive_keys`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `secret`, `keys`.

## Function `quic_initial_derive`

Derives the Initial keys of a checked connection ID.

### Signature

```
quic_initial_derive(keys, dcid)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `keys` | output | [`InitialKeys`](#type-initialkeys) |
| `dcid` | input | [`ConnectionId`](#type-connectionid) of at most 20 bytes |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 384 bytes on x86-64 (return address included), 384 bytes on ARM64, 400 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_initial_derive`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `keys`, `dcid`.

## Function `quic_nonce`

Builds the AEAD nonce of a packet: the IV XOR the packet number (RFC 9001 section 5.3).

### Signature

```
quic_nonce(dst, keys, pn)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | 16 bytes: the nonce, then 4 zero bytes |
| `keys` | input | [`PacketKeys`](#type-packetkeys) |
| `pn` | input | u64 |

### Function does

- XORs the packet number, big endian, into the last 8 bytes of the 12-byte IV.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_nonce`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `dst`, `keys`, `pn`.

## Function `quic_hp_mask`

Computes AES-ECB(hp, sample), the header protection mask (RFC 9001 section 5.4.3).

### Signature

```
quic_hp_mask(hp, sample, mask)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `hp` | input | 16 bytes |
| `sample` | input | 16 bytes at any address |
| `mask` | output | 16 bytes |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 192 bytes on x86-64 (return address included), 192 bytes on ARM64, 208 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_hp_mask`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `hp`, `sample`, `mask`.

## Function `quic_pn_decode`

Decodes the packet number closest to largest + 1 that ends in the truncated bits (RFC 9000 appendix A.3).

### Signature

```
quic_pn_decode(truncated, bits, largest) -> pn
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `truncated` | input | u64 |
| `bits` | input | u64: 8, 16, 24 or 32 |
| `largest` | input | u64: the largest received, or NONE |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_pn_decode`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- It returns the packet number, not a status.
- Argument order: `truncated`, `bits`, `largest`.

## Function `quic_mask_header`

XORs a header protection mask into a header.

### Signature

```
quic_mask_header(buf, pn_offset, pn_len, mask)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `buf` | input and output | the header |
| `pn_offset` | input | u64 |
| `pn_len` | input | u64: 1 to 4 |
| `mask` | input | 16 bytes |

### Function does

- Masks 4 bits of the first byte of a long header, 5 of a short one.
- Masks the packet number bytes with mask bytes 1 to 4.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_mask_header`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `buf`, `pn_offset`, `pn_len`, `mask`.

## Function `quic_seal`

Protects the packet in buf in place: the sealed frames and the tag after the header, then header protection.

### Signature

```
quic_seal(keys, buf, header_len, payload_len, pn, work) -> length
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `keys` | input | [`PacketKeys`](#type-packetkeys) |
| `buf` | input and output | the header, its packet number last, then the frames |
| `header_len` | input | u64, at most 256 |
| `payload_len` | input | u64, at most 1504 |
| `pn` | input | u64 |
| `work` | scratch | 3400 bytes at a multiple of 8 |

### Caller must

- Keep payload_len plus the packet number length at 4 or more.

### Function does

- Returns header_len + payload_len + 16.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_seal`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- It returns the length, not a status.
- Argument order: `keys`, `buf`, `header_len`, `payload_len`, `pn`, `work`.

## Function `quic_open`

Removes the header protection of a packet in place, decodes its packet number and decrypts its frames after the header.

### Signature

```
quic_open(keys, buf, pn_offset, total, largest, work, result) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `keys` | input | [`PacketKeys`](#type-packetkeys) |
| `buf` | input and output | `total` bytes |
| `pn_offset` | input | u64 |
| `total` | input | u64 |
| `largest` | input | u64: the largest received, or NONE |
| `work` | scratch | 3400 bytes at a multiple of 8 |
| `result` | output | three u64: the packet number, the header length, the payload length |

### Returns

- `QUIC_OK`: The packet opened.
- `QUIC_INVALID_PACKET`: The packet is too short for the sample or the tag, or its header or sealed payload is too long for the work area.
- `QUIC_DECRYPT_FAILED`: The tag does not match.

### Function never

- Makes an OS call.

### Effects

- `buf` may change when the status is not `QUIC_OK`.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_open`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- x86-64: the seventh argument `result` is in r10.
- Argument order: `keys`, `buf`, `pn_offset`, `total`, `largest`, `work`, `result`.

## Type `ConnectionId`

A QUIC connection ID of 0 to 20 bytes.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `length` | u64 | Bytes of the ID: 0 to 20 |
| 8 | `id` | 24 bytes | The ID, then zero bytes |

### Rules

- Size: 32 bytes.


## Type `PacketKeys`

The keys of one direction of a packet number space.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `key` | 16 bytes | The AES-128-GCM key |
| 16 | `iv` | 16 bytes | The 12-byte IV, then 4 zero bytes |
| 32 | `hp` | 16 bytes | The header protection key |

### Rules

- Size: 48 bytes.


## Type `InitialKeys`

The Initial keys of both directions.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `client` | [`PacketKeys`](#type-packetkeys) | The keys of packets the client sends |
| 48 | `server` | [`PacketKeys`](#type-packetkeys) | The keys of packets the server sends |

### Rules

- Size: 96 bytes.


## Type `PlainPacket`

A packet to protect: its number, its header and its frames.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value |
| 8 | `number` | u64 | The full packet number |
| 16 | `header_off` | u64 | Offset of the header, its truncated packet number last |
| 24 | `header_count` | u64 | Bytes of the header |
| 32 | `payload_off` | u64 | Offset of the frames |
| 40 | `payload_count` | u64 | Bytes of the frames |

### Rules

- Each offset is 48 or more, and each part ends inside `size`.


## Type `OpenRequest`

A protected packet to open.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value |
| 8 | `pn_offset` | u64 | Where the packet number starts in the packet |
| 16 | `largest` | u64 | The largest packet number received in the space, or NONE |
| 24 | `packet_off` | u64 | Offset of the packet |
| 32 | `packet_count` | u64 | Bytes of the packet |

### Rules

- The packet offset is 40 or more, and the packet ends inside `size`.


## Type `OpenedPacket`

An opened packet: its number, its header and its frames.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes the caller gives |
| 8 | `number` | u64 | The full packet number |
| 16 | `header_off` | u64 | Offset of the header without protection: 48 |
| 24 | `header_count` | u64 | Bytes of the header |
| 32 | `payload_off` | u64 | Offset of the frames: the first multiple of 8 after the header |
| 40 | `payload_count` | u64 | Bytes of the frames |

### Rules

- `size` is at least the packet length + 56.


## Type `PacketScratch`

The work area of `quic_packet_seal` and `quic_packet_open`.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the scratch |

### Rules

- Size: at least `QUIC_PACKET_SCRATCH` (5208) bytes, at a multiple of 8.


## Test vectors

- RFC 9001 appendix A
  - File: rfc9001.bin, from [tests/generator/vectors.py](../../tests/generator/vectors.py).
- Generated packets
  - File: packet-generated.bin, from [tests/generator/vectors.py](../../tests/generator/vectors.py).
  - Expected results: the pinned `cryptography` package and the steps of RFC 9001 section 5, checked first against appendix A.

## Results

<!-- CI generates the tick table for each function here. -->

### `quic_initial_keys`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_packet_seal`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_packet_open`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_retry_tag`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_expand_label`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_derive_keys`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_initial_derive`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_nonce`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_hp_mask`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_pn_decode`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_mask_header`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_seal`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_open`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |
