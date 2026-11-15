# TLS handshake

## Contents

### Functions

- [`quic_rd8`](#function-quic_rd8): reads one byte.
- [`quic_rd16`](#function-quic_rd16): reads a 2-byte big-endian number.
- [`quic_rd24`](#function-quic_rd24): reads a 3-byte big-endian number.
- [`quic_tls_append`](#function-quic_tls_append): adds a handshake message to the transcript.
- [`quic_tls_hash`](#function-quic_tls_hash): hashes the transcript.
- [`quic_hkdf_extract`](#function-quic_hkdf_extract): computes HKDF-Extract.
- [`quic_derive_secret`](#function-quic_derive_secret): computes Derive-Secret.
- [`quic_finished_mac`](#function-quic_finished_mac): computes the MAC of a Finished message.
- [`quic_handshake_keys`](#function-quic_handshake_keys): derives the Handshake keys.
- [`quic_app_keys`](#function-quic_app_keys): derives the 1-RTT keys.
- [`quic_install_keys`](#function-quic_install_keys): installs the keys of a packet number space.
- [`quic_next_rx_keys`](#function-quic_next_rx_keys): derives the receive keys of the next key phase.
- [`quic_key_update`](#function-quic_key_update): moves to the next key phase.
- [`quic_crypto_out`](#function-quic_crypto_out): sends a handshake message.
- [`quic_key_share`](#function-quic_key_share): makes our key share.
- [`quic_shared`](#function-quic_shared): computes the ECDHE shared secret.
- [`quic_cert_message`](#function-quic_cert_message): writes our Certificate message.
- [`quic_cv_message`](#function-quic_cv_message): writes our CertificateVerify message.
- [`quic_cv_put`](#function-quic_cv_put): builds what a CertificateVerify signs.
- [`quic_fin_message`](#function-quic_fin_message): writes a Finished message.
- [`quic_tp_int`](#function-quic_tp_int): writes one integer transport parameter.
- [`quic_tp_write`](#function-quic_tp_write): writes our transport parameters.
- [`quic_cid_is`](#function-quic_cid_is): compares bytes with a connection ID.
- [`quic_tp_read`](#function-quic_tp_read): reads the transport parameters of the peer.
- [`quic_client_hello`](#function-quic_client_hello): sends our ClientHello.
- [`quic_tls_start`](#function-quic_tls_start): starts the handshake of a client.
- [`quic_on_server_hello`](#function-quic_on_server_hello): takes a ServerHello or a HelloRetryRequest.
- [`quic_message_hash`](#function-quic_message_hash): replaces ClientHello1 in the transcript.
- [`quic_on_ee`](#function-quic_on_ee): takes EncryptedExtensions.
- [`quic_alpn_libp2p`](#function-quic_alpn_libp2p): checks an ALPN list.
- [`quic_sigalgs_ok`](#function-quic_sigalgs_ok): checks a signature_algorithms list.
- [`quic_on_cr`](#function-quic_on_cr): takes a CertificateRequest.
- [`quic_on_cert`](#function-quic_on_cert): takes the Certificate of the peer.
- [`quic_peer_id_ok`](#function-quic_peer_id_ok): checks the peer ID the dialer named.
- [`quic_on_cv`](#function-quic_on_cv): takes the CertificateVerify of the peer.
- [`quic_on_fin`](#function-quic_on_fin): takes the Finished of the peer.
- [`quic_client_finish`](#function-quic_client_finish): ends the handshake of a client.
- [`quic_on_client_hello`](#function-quic_on_client_hello): takes a ClientHello.
- [`quic_server_hello`](#function-quic_server_hello): sends a ServerHello or a HelloRetryRequest.
- [`quic_server_flight`](#function-quic_server_flight): sends the server flight.
- [`quic_tls_message`](#function-quic_tls_message): takes one handshake message of the peer.
- [`quic_append_in`](#function-quic_append_in): adds a message of the peer to the transcript.
- [`quic_handshake_complete`](#function-quic_handshake_complete): completes the TLS handshake.
- [`quic_tls_feed`](#function-quic_tls_feed): takes the complete handshake messages of a space.
- [`quic_crx_compact`](#function-quic_crx_compact): moves untaken CRYPTO data to the start of its block.
- [`quic_maybe_key_update`](#function-quic_maybe_key_update): starts a key update when one is due.
- [`quic_phase_start`](#function-quic_phase_start): starts a key phase.

## Spec

- Document: [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) section 4 and [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446).
- Document: [tls/tls.md](https://github.com/libp2p/specs/blob/c750236de43cd8b246a824b377dfdb26bae686db/tls/tls.md), libp2p/specs at commit c750236.
- Section: the TLS 1.3 handshake of the libp2p TLS profile: TLS_AES_128_GCM_SHA256, x25519 and secp256r1 with HelloRetryRequest, ecdsa_secp256r1_sha256 signed and ed25519 accepted, the ALPN "libp2p", mutual authentication, key updates.

## Function `quic_rd8`

Reads one byte.

### Signature

```
quic_rd8(p, end) -> (next, value)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the byte |
| `end` | input | the end of the data |

### Function does

- Returns p + 1 and the byte, or 0 when p is at or past `end`.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_rd8`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- It returns two values: x0, rax or a0, then x1, rdx or a1.
- Argument order: `p`, `end`.

## Function `quic_rd16`

Reads a 2-byte big-endian number.

### Signature

```
quic_rd16(p, end) -> (next, value)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the bytes |
| `end` | input | the end of the data |

### Function does

- Returns p + 2 and the value, or 0 when the bytes pass `end`.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_rd16`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- It returns two values: x0, rax or a0, then x1, rdx or a1.
- Argument order: `p`, `end`.

## Function `quic_rd24`

Reads a 3-byte big-endian number.

### Signature

```
quic_rd24(p, end) -> (next, value)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the bytes |
| `end` | input | the end of the data |

### Function does

- Returns p + 3 and the value, or 0 when the bytes pass `end`.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_rd24`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- It returns two values: x0, rax or a0, then x1, rdx or a1.
- Argument order: `p`, `end`.

## Function `quic_tls_append`

Adds a handshake message to the transcript.

### Signature

```
quic_tls_append(msg, n) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `msg` | input | `n` bytes |
| `n` | input | u64 |

### Function does

- Returns 0, or the error code to close with: INTERNAL_ERROR when the transcript has no room.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_tls_append`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the TLS block in x20, rbp, s2.
- Argument order: `msg`, `n`.

## Function `quic_tls_hash`

Hashes the transcript.

### Signature

```
quic_tls_hash()
```

### Function does

- Puts the SHA-256 of the transcript in the TLS block.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_tls_hash`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the TLS block in x20, rbp, s2.

## Function `quic_hkdf_extract`

Computes HKDF-Extract.

### Signature

```
quic_hkdf_extract(salt, ikm, out)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `salt` | input | 32 bytes, or 0 for 32 zero bytes |
| `ikm` | input | 32 bytes, or 0 for 32 zero bytes |
| `out` | output | 32 bytes |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 368 bytes on x86-64 (return address included), 368 bytes on ARM64, 384 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_hkdf_extract`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `salt`, `ikm`, `out`.

## Function `quic_derive_secret`

Computes Derive-Secret of RFC 8446 section 7.1 with the transcript hash as it is.

### Signature

```
quic_derive_secret(secret, label, label_len, out)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `secret` | input | 32 bytes |
| `label` | input | `label_len` bytes |
| `label_len` | input | u64 |
| `out` | output | 32 bytes |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_derive_secret`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the TLS block in x20, rbp, s2.
- Argument order: `secret`, `label`, `label_len`, `out`.

## Function `quic_finished_mac`

Computes the MAC of a Finished message.

### Signature

```
quic_finished_mac(secret, out)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `secret` | input | 32 bytes: a handshake traffic secret |
| `out` | output | 32 bytes |

### Function does

- Takes finished_key = HKDF-Expand-Label(secret, "finished", "", 32).
- Returns HMAC-SHA256(finished_key, the transcript hash).

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 368 bytes on x86-64 (return address included), 368 bytes on ARM64, 384 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_finished_mac`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the TLS block in x20, rbp, s2.
- Argument order: `secret`, `out`.

## Function `quic_handshake_keys`

Derives the handshake secret and the Handshake keys of both directions after ServerHello.

### Signature

```
quic_handshake_keys()
```

### Function does

- Takes the handshake secret from the ECDHE shared secret.
- Derives the client and server handshake traffic secrets.
- Installs the Handshake keys for our role.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_handshake_keys`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1; the TLS block in x20, rbp, s2.

## Function `quic_app_keys`

Derives the application traffic secrets and the 1-RTT keys once the server Finished is in the transcript.

### Signature

```
quic_app_keys()
```

### Function does

- Keeps the two secrets in the connection for key updates.
- Installs the 1-RTT keys for our role.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_app_keys`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1; the TLS block in x20, rbp, s2.

## Function `quic_install_keys`

Installs the keys of a packet number space.

### Signature

```
quic_install_keys(space, client_secret, server_secret)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |
| `client_secret` | input | 32 bytes |
| `server_secret` | input | 32 bytes |

### Function does

- Derives both directions and gives each its role: the client sends with the client secret.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_install_keys`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1.
- Argument order: `space`, `client_secret`, `server_secret`.

## Function `quic_next_rx_keys`

Derives the receive keys of the next key phase (RFC 9001 section 6).

### Signature

```
quic_next_rx_keys()
```

### Function does

- Takes the key and IV of HKDF-Expand-Label(the peer secret, "quic ku", "", 32).
- Keeps the header protection key.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 176 bytes on x86-64 (return address included), 176 bytes on ARM64, 192 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_next_rx_keys`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1.

## Function `quic_key_update`

Moves to the next key phase (RFC 9001 section 6).

### Signature

```
quic_key_update()
```

### Function does

- Makes the current receive keys the previous ones, and the next ones current.
- Steps the peer secret and ours on.
- Derives our new send keys.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 128 bytes on x86-64 (return address included), 128 bytes on ARM64, 144 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_key_update`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1.

## Function `quic_crypto_out`

Sends a handshake message.

### Signature

```
quic_crypto_out(space, msg, n) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |
| `msg` | input | `n` bytes |
| `n` | input | u64 |

### Function does

- Appends the message to the CRYPTO send data of the space and to the transcript.
- Returns 0, or the error code to close with.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_crypto_out`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1; the TLS block in x20, rbp, s2.
- Argument order: `space`, `msg`, `n`.

## Function `quic_key_share`

Makes our key share.

### Signature

```
quic_key_share(group, dst) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `group` | input | u64: x25519 (0x1D) or secp256r1 (0x17) |
| `dst` | output | 32 or 65 bytes |

### Function does

- Draws a new private key into the TLS block.
- Writes the X25519 key of 32 bytes or the P-256 point of 65 bytes, and returns `dst` after it.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 208 bytes on x86-64 (return address included), 208 bytes on ARM64, 224 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_key_share`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the TLS block in x20, rbp, s2.
- Argument order: `group`, `dst`.

## Function `quic_shared`

Computes the ECDHE shared secret.

### Signature

```
quic_shared(key, n) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `key` | input | the peer key share |
| `n` | input | u64 |

### Function does

- Puts the shared secret of our key and the peer key for the group into the TLS block.
- Returns 0, or the alert error when the key has the wrong length or is not valid.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 176 bytes on x86-64 (return address included), 176 bytes on ARM64, 192 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_shared`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the TLS block in x20, rbp, s2.
- Argument order: `key`, `n`.

## Function `quic_cert_message`

Writes our Certificate message.

### Signature

```
quic_cert_message(dst) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | the message |

### Function does

- Writes an empty context and our certificate, and returns `dst` after them.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_cert_message`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `dst`.

## Function `quic_cv_message`

Writes our CertificateVerify message.

### Signature

```
quic_cv_message(dst, server) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | the message |
| `server` | input | u64: 1 when we are the server |

### Function does

- Signs with ECDSA P-256 the SHA-256 of 64 spaces, the context string of our side, a zero byte and the transcript hash.
- Writes the signature in DER, and returns `dst` after the message.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 352 bytes on x86-64 (return address included), 352 bytes on ARM64, 368 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_cv_message`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the TLS block in x20, rbp, s2; the state in x27, r15, s9.
- Argument order: `dst`, `server`.

## Function `quic_cv_put`

Builds the content a CertificateVerify signs (RFC 8446 section 4.4.3).

### Signature

```
quic_cv_put(list, server, hash)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `list` | output | [`ByteList`](node.md#type-bytelist) |
| `server` | input | u64: 1 for the server context string |
| `hash` | input | 32 bytes |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_cv_put`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `list`, `server`, `hash`.

## Function `quic_fin_message`

Writes a Finished message.

### Signature

```
quic_fin_message(dst, secret) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | 36 bytes |
| `secret` | input | 32 bytes |

### Function does

- Writes the MAC of the secret over the transcript hash.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_fin_message`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the TLS block in x20, rbp, s2.
- Argument order: `dst`, `secret`.

## Function `quic_tp_int`

Writes one integer transport parameter.

### Signature

```
quic_tp_int(dst, id, v) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | the parameter |
| `id` | input | u64 |
| `v` | input | u64, below 2^62 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_tp_int`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `dst`, `id`, `v`.

## Function `quic_tp_write`

Writes our transport parameters (RFC 9000 section 18).

### Signature

```
quic_tp_write(dst) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | the parameters |

### Function does

- Writes max_idle_timeout, max_udp_payload_size 1452, the flow control limits and initial_max_streams_bidi.
- Writes disable_active_migration and initial_source_connection_id.
- A server adds original_destination_connection_id.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_tp_write`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1.
- Argument order: `dst`.

## Function `quic_cid_is`

Compares bytes with a connection ID.

### Signature

```
quic_cid_is(p, n, cid) -> equal
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | `n` bytes |
| `n` | input | u64 |
| `cid` | input | [`ConnectionId`](packet-protection.md#type-connectionid) |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_cid_is`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `p`, `n`, `cid`.

## Function `quic_tp_read`

Reads the transport parameters of the peer.

### Signature

```
quic_tp_read(p, end) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the parameters |
| `end` | input | their end |

### Function does

- Skips unknown parameters.
- Takes each known parameter once, into the connection.
- Checks the connection IDs and the limits of RFC 9000 section 18.2.
- Returns 0, or TRANSPORT_PARAMETER_ERROR.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_tp_read`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1.
- Argument order: `p`, `end`.

## Function `quic_client_hello`

Sends our ClientHello.

### Signature

```
quic_client_hello() -> error
```

### Function does

- Offers TLS_AES_128_GCM_SHA256 and TLS 1.3.
- Offers the groups x25519 and secp256r1, and a key share of the chosen group.
- Offers ecdsa_secp256r1_sha256 and ed25519.
- Offers the ALPN "libp2p" and our transport parameters.
- Echoes the cookie of a HelloRetryRequest.
- Sends it on the Initial CRYPTO stream.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_client_hello`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1; the TLS block in x20, rbp, s2.

## Function `quic_tls_start`

Starts the handshake of a client.

### Signature

```
quic_tls_start() -> error
```

### Function does

- Sends a ClientHello with an x25519 key share.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_tls_start`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1; the TLS block in x20, rbp, s2.

## Function `quic_on_server_hello`

Takes a ServerHello or a HelloRetryRequest.

### Signature

```
quic_on_server_hello(p, end) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the message body |
| `end` | input | its end |

### Function does

- Checks the version, the cipher suite and the key share.
- For a HelloRetryRequest, sends a new ClientHello for the group it names, once.
- For a ServerHello, derives the Handshake keys.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_server_hello`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1; the TLS block in x20, rbp, s2.
- Argument order: `p`, `end`.

## Function `quic_message_hash`

Replaces ClientHello1 in the transcript with its message_hash after a HelloRetryRequest (RFC 8446 section 4.4.1).

### Signature

```
quic_message_hash()
```

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_message_hash`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the TLS block in x20, rbp, s2.

## Function `quic_on_ee`

Takes EncryptedExtensions.

### Signature

```
quic_on_ee(p, end) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the message body |
| `end` | input | its end |

### Function does

- Requires the ALPN "libp2p" and the transport parameters.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_ee`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1; the TLS block in x20, rbp, s2.
- Argument order: `p`, `end`.

## Function `quic_alpn_libp2p`

Checks an ALPN list.

### Signature

```
quic_alpn_libp2p(p, end) -> found
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the ALPN extension data |
| `end` | input | its end |

### Function does

- Returns 1 when the list holds "libp2p".

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_alpn_libp2p`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `p`, `end`.

## Function `quic_sigalgs_ok`

Checks a signature_algorithms list.

### Signature

```
quic_sigalgs_ok(p, end) -> found
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the extension data |
| `end` | input | its end |

### Function does

- Returns 1 when the list holds ecdsa_secp256r1_sha256.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_sigalgs_ok`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `p`, `end`.

## Function `quic_on_cr`

Takes a CertificateRequest.

### Signature

```
quic_on_cr(p, end) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the message body |
| `end` | input | its end |

### Function does

- Requires an empty context and ecdsa_secp256r1_sha256 among the signature algorithms.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_cr`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the TLS block in x20, rbp, s2.
- Argument order: `p`, `end`.

## Function `quic_on_cert`

Takes the Certificate of the peer.

### Signature

```
quic_on_cert(p, end) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the message body |
| `end` | input | its end |

### Function does

- Requires an empty context and exactly one certificate.
- Checks it with `quic_cert_check` at the Unix time of the step.
- A dialer checks the peer ID it named (`quic_peer_id_ok`).

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_cert`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1; the TLS block in x20, rbp, s2.
- Argument order: `p`, `end`.

## Function `quic_peer_id_ok`

Checks the peer ID the dialer named.

### Signature

```
quic_peer_id_ok() -> equal
```

### Function does

- Takes the multihash of the host key: identity for a protobuf of at most 42 bytes, else SHA-256.
- Returns 1 when it equals the peer ID of the DIAL.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 304 bytes on x86-64 (return address included), 304 bytes on ARM64, 320 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_peer_id_ok`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the TLS block in x20, rbp, s2.

## Function `quic_on_cv`

Takes the CertificateVerify of the peer.

### Signature

```
quic_on_cv(p, end, server) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the message body |
| `end` | input | its end |
| `server` | input | u64: 1 when the peer is the server |

### Function does

- Verifies ecdsa_secp256r1_sha256 in DER for a P-256 key, or ed25519 for an Ed25519 key, over the transcript hash.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 432 bytes on x86-64 (return address included), 432 bytes on ARM64, 448 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_cv`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the TLS block in x20, rbp, s2.
- Argument order: `p`, `end`, `server`.

## Function `quic_on_fin`

Takes the Finished of the peer.

### Signature

```
quic_on_fin(p, end, secret) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the message body |
| `end` | input | its end |
| `secret` | input | 32 bytes: the handshake traffic secret of the peer |

### Function does

- Requires the MAC of the secret over the transcript hash.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 128 bytes on x86-64 (return address included), 128 bytes on ARM64, 144 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_fin`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the TLS block in x20, rbp, s2.
- Argument order: `p`, `end`, `secret`.

## Function `quic_client_finish`

Ends the handshake of a client.

### Signature

```
quic_client_finish() -> error
```

### Function does

- Derives the 1-RTT keys.
- Sends our Certificate and CertificateVerify when the server asked.
- Sends our Finished on the Handshake CRYPTO stream.
- Completes the handshake.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_client_finish`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1; the TLS block in x20, rbp, s2.

## Function `quic_on_client_hello`

Takes a ClientHello.

### Signature

```
quic_on_client_hello(p, end) -> result
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the message body |
| `end` | input | its end |

### Function does

- Requires TLS 1.3, TLS_AES_128_GCM_SHA256, ecdsa_secp256r1_sha256, the ALPN "libp2p" and transport parameters.
- Takes a key share of x25519 or secp256r1.
- Returns 0, 2 when a HelloRetryRequest is due, or the error code.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_client_hello`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1; the TLS block in x20, rbp, s2.
- Argument order: `p`, `end`.

## Function `quic_server_hello`

Sends a ServerHello or a HelloRetryRequest.

### Signature

```
quic_server_hello(hrr) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `hrr` | input | u64: 1 for a HelloRetryRequest |

### Function does

- Sends it on the Initial CRYPTO stream.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_server_hello`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1; the TLS block in x20, rbp, s2.
- Argument order: `hrr`.

## Function `quic_server_flight`

Sends the server flight.

### Signature

```
quic_server_flight() -> error
```

### Function does

- Sends ServerHello and derives the Handshake keys.
- Sends EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify and Finished on the Handshake CRYPTO stream.
- Derives the 1-RTT keys.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_server_flight`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1; the TLS block in x20, rbp, s2.

## Function `quic_tls_message`

Takes one handshake message of the peer.

### Signature

```
quic_tls_message(space, type, p, end) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |
| `type` | input | u64: the message type |
| `p` | input | the message body |
| `end` | input | its end |

### Function does

- Takes the message in the order of the stage, in the space the stage expects.
- Returns CRYPTO_ERROR 0x10A (the unexpected_message alert) for any other.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_tls_message`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1; the TLS block in x20, rbp, s2.
- Argument order: `space`, `type`, `p`, `end`.

## Function `quic_append_in`

Adds a message of the peer to the transcript.

### Signature

```
quic_append_in() -> error
```

### Function does

- Adds the 4-byte header and the body.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_append_in`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the TLS block in x20, rbp, s2.
- ARM64 and RISC-V take the body in x23 or s5 and its end in x24 or s6; x86-64 takes them as the arguments rdi and rsi.

## Function `quic_handshake_complete`

Completes the TLS handshake (RFC 9001 section 4.1.1).

### Signature

```
quic_handshake_complete()
```

### Function does

- A server confirms it at once and sends HANDSHAKE_DONE.
- The application hears CONNECTED.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_handshake_complete`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1; the TLS block in x20, rbp, s2.

## Function `quic_tls_feed`

Takes the complete handshake messages of a space.

### Signature

```
quic_tls_feed(space) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |

### Function does

- Hands each complete message at the start of the CRYPTO data to `quic_tls_message`, in order.
- Keeps the rest.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_tls_feed`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1.
- Argument order: `space`.

## Function `quic_crx_compact`

Moves untaken CRYPTO data to the start of its block.

### Signature

```
quic_crx_compact()
```

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_crx_compact`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the space in x21, r12, s3.

## Function `quic_maybe_key_update`

Starts a key update (RFC 9001 section 6) when one is due.

### Signature

```
quic_maybe_key_update()
```

### Function does

- Requires the handshake confirmed, the previous keys gone, and a packet of the current phase acknowledged.
- Requires QUIC_CFG_KEY_UPDATE packets sent in the phase (1000000 when 0, far below the 2^23 packets AES-128-GCM may protect).

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 16 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_maybe_key_update`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.

## Function `quic_phase_start`

Starts a key phase.

### Signature

```
quic_phase_start()
```

### Function does

- Records our first packet number of the new phase.
- Keeps the previous receive keys for 3 PTO.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 16 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_phase_start`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.

## Test vectors

- Scenarios
  - File: [tests/runner/runner.c](../../tests/runner/runner.c): handshake, key_update, key_update_loss, peer_id and secp256k1.
- transport-interop of libp2p/test-plans
  - File: [tests/interop/](../../tests/interop/).

## Results

<!-- CI generates the tick table for each function here. -->
