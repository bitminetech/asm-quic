# Connections

Connection slots, IDs and closing.

## Contents

### Functions

- [`quic_conn_new`](#function-quic_conn_new): starts a connection slot.
- [`quic_conn_free`](#function-quic_conn_free): frees a connection.
- [`quic_space`](#function-quic_space): gives the record of a packet number space.
- [`quic_conn_find`](#function-quic_conn_find): finds a connection by our connection ID.
- [`quic_conn_find_odcid`](#function-quic_conn_find_odcid): finds a server connection by the first ID of its client.
- [`quic_pto_period`](#function-quic_pto_period): gives the probe timeout.
- [`quic_conn_close`](#function-quic_conn_close): closes a connection.
- [`quic_conn_drain`](#function-quic_conn_drain): drains a connection.
- [`quic_close_timer`](#function-quic_close_timer): sets the end of closing or draining.
- [`quic_discard_space`](#function-quic_discard_space): discards the keys of a packet number space.
- [`quic_confirm`](#function-quic_confirm): confirms the handshake.
- [`quic_idle_reset`](#function-quic_idle_reset): starts the idle timer again.

## Spec

- Document: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000).
- Section: 5 (connections and connection IDs) and 10 (closing).

## Function `quic_conn_new`

Starts a connection slot.

### Signature

```
quic_conn_new(role) -> conn
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `role` | input | u64: 0 client, 1 server |

### Function does

- Sets the fields to their start values.
- Draws our connection ID: the slot index, 16 bits of the generation, 4 random bytes.
- Allocates the ring of sent packets and the TLS block.
- Returns 0 when no slot or heap is free.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_conn_new`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `role`.

## Function `quic_conn_free`

Frees a connection.

### Signature

```
quic_conn_free(conn)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `conn` | input | a connection slot |

### Function does

- Frees its heap blocks and streams, then the slot.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_conn_free`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `conn`.

## Function `quic_space`

Gives the record of a packet number space.

### Signature

```
quic_space(conn, space) -> record
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `conn` | input | a connection slot |
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_space`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `conn`, `space`.

## Function `quic_conn_find`

Finds a connection by our connection ID.

### Signature

```
quic_conn_find(dcid, n) -> conn
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dcid` | input | `n` bytes |
| `n` | input | u64 |

### Function does

- Takes the slot index from the first bytes of the 8-byte ID.
- Returns the connection whose ID matches, or 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_conn_find`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `dcid`, `n`.

## Function `quic_conn_find_odcid`

Finds a server connection by the first ID of its client.

### Signature

```
quic_conn_find_odcid(dcid, n, socket, addr) -> conn
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dcid` | input | `n` bytes |
| `n` | input | u64 |
| `socket` | input | u64 |
| `addr` | input | [`Address`](node.md#type-address) |

### Function does

- Returns the server connection still in its handshake that the client began with this ID from this address, or 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_conn_find_odcid`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `dcid`, `n`, `socket`, `addr`.

## Function `quic_pto_period`

Gives the probe timeout of RFC 9002 section 6.2.1.

### Signature

```
quic_pto_period(conn, space) -> microseconds
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `conn` | input | a connection slot |
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |

### Function does

- Takes smoothed_rtt + max(4 * rttvar, 1 ms), plus max_ack_delay in the Application space.
- Doubles it for each PTO in a row, at most 16 times.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_pto_period`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `conn`, `space`.

## Function `quic_conn_close`

Closes a connection: CONNECTION_CLOSE goes out (RFC 9000 section 10.2), then it stays closing for 3 PTO.

### Signature

```
quic_conn_close(conn, error, reason)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `conn` | input | a connection slot |
| `error` | input | u64: the QUIC error code |
| `reason` | input | u64: the `QUIC_ERR_*` the application hears |

### Function does

- Keeps a reason set before.
- Leaves a connection already closing or draining as it is.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_conn_close`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `conn`, `error`, `reason`.

## Function `quic_conn_drain`

Drains a connection the peer closed or reset: it sends nothing for 3 PTO (RFC 9000 section 10.2.2).

### Signature

```
quic_conn_drain(conn, error)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `conn` | input | a connection slot |
| `error` | input | u64: the QUIC error code of the peer |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_conn_drain`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `conn`, `error`.

## Function `quic_close_timer`

Sets the end of closing or draining.

### Signature

```
quic_close_timer(conn)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `conn` | input | a connection slot |

### Function does

- Sets it to now + 3 PTO.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_close_timer`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `conn`.

## Function `quic_discard_space`

Discards the keys of a packet number space (RFC 9001 section 4.9).

### Signature

```
quic_discard_space(space)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |

### Function does

- Takes its packets out of the bytes in flight.
- Frees its CRYPTO buffers.
- Starts the probe count again (RFC 9002 section 6.2.2).

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_discard_space`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `space`.

## Function `quic_confirm`

Confirms the handshake.

### Signature

```
quic_confirm()
```

### Function does

- Discards the Handshake keys.
- Frees the TLS block.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_confirm`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.

## Function `quic_idle_reset`

Starts the idle timer again (RFC 9000 section 10.1).

### Signature

```
quic_idle_reset()
```

### Function does

- Takes the smaller of our and the peer max_idle_timeout, at least 3 PTO.
- Sets no timer when both are 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_idle_reset`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.

## Test vectors

- Scenarios
  - File: [tests/runner/runner.c](../../tests/runner/runner.c): handshake, timeout, idle, reset, errors and limits.

## Results

<!-- CI generates the tick table for each function here. -->

### `quic_conn_new`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_conn_free`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_space`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_conn_find`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_conn_find_odcid`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_pto_period`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_conn_close`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_conn_drain`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_close_timer`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_discard_space`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_confirm`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_idle_reset`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |
