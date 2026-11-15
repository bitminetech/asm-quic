# Streams

## Contents

### Functions

- [`quic_stream_new`](#function-quic_stream_new): starts a stream slot.
- [`quic_stream_free`](#function-quic_stream_free): frees a stream.
- [`quic_stream_find`](#function-quic_stream_find): finds a stream of the connection by ID.
- [`quic_assign_ids`](#function-quic_assign_ids): gives IDs to our waiting streams.
- [`quic_on_open_stream`](#function-quic_on_open_stream): opens a stream for the application.
- [`quic_on_stream_write`](#function-quic_on_stream_write): queues bytes on a stream.
- [`quic_on_stream_close`](#function-quic_on_stream_close): ends the bytes of a stream.
- [`quic_on_stream_reset`](#function-quic_on_stream_reset): resets a stream for the application.
- [`quic_stream_reset_local`](#function-quic_stream_reset_local): resets a stream both ways.
- [`quic_stream_drop`](#function-quic_stream_drop): frees the send queue of a stream.
- [`quic_stream_drop_rx`](#function-quic_stream_drop_rx): frees the received segments of a stream.
- [`quic_stream_acked`](#function-quic_stream_acked): handles an acknowledged STREAM frame.
- [`quic_stream_advance`](#function-quic_stream_advance): moves the acknowledged offset of a stream.
- [`quic_stream_lost`](#function-quic_stream_lost): handles a lost STREAM frame.
- [`quic_stream_reset_acked`](#function-quic_stream_reset_acked): ends our side of a reset stream.
- [`quic_ranges_add`](#function-quic_ranges_add): adds a range to a stream range list.
- [`quic_ranges_remove`](#function-quic_ranges_remove): removes a range from a stream range list.
- [`quic_peer_stream`](#function-quic_peer_stream): finds the stream of a frame of the peer.
- [`quic_rx_limits`](#function-quic_rx_limits): checks flow control and final size for received data.
- [`quic_on_stream_frame`](#function-quic_on_stream_frame): handles a STREAM frame.
- [`quic_segment_add`](#function-quic_segment_add): stores received bytes.
- [`quic_on_reset_stream`](#function-quic_on_reset_stream): handles a RESET_STREAM frame.
- [`quic_on_stop_sending`](#function-quic_on_stop_sending): handles a STOP_SENDING frame.
- [`quic_on_max_stream_data`](#function-quic_on_max_stream_data): handles a MAX_STREAM_DATA frame.
- [`quic_stream_tell`](#function-quic_stream_tell): tells the application what happened on a stream.
- [`quic_stream_credit`](#function-quic_stream_credit): gives new flow control credit.

## Spec

- Document: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000).
- Section: 2 (streams), 3 (stream states), 4 (flow control).

## Function `quic_stream_new`

Starts a stream slot.

### Signature

```
quic_stream_new(id, local) -> stream
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `id` | input | u64: the stream ID, or NONE until MAX_STREAMS allows one |
| `local` | input | u64: 1 when we open it |

### Function does

- Links the stream first in the list of the connection.
- Returns 0 when no slot is free.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_new`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `id`, `local`.

## Function `quic_stream_free`

Frees a stream.

### Signature

```
quic_stream_free(stream)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `stream` | input | a stream slot |

### Function does

- Frees its chunks and segments, unlinks it from its connection, and frees the slot.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_free`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `stream`.

## Function `quic_stream_find`

Finds a stream of the connection by ID.

### Signature

```
quic_stream_find(id) -> stream
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `id` | input | u64 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_find`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `id`.

## Function `quic_assign_ids`

Gives IDs to our waiting streams.

### Signature

```
quic_assign_ids()
```

### Function does

- Gives IDs while the MAX_STREAMS of the peer allows: 4n for a client, 4n + 1 for a server.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_assign_ids`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.

## Function `quic_on_open_stream`

Opens a stream for the application.

### Signature

```
quic_on_open_stream(event)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `event` | input | [`OpenStreamEvent`](node.md#type-openstreamevent) |

### Function does

- Opens a stream of ours; its ID comes when MAX_STREAMS allows.
- Adds STREAM_OPENED with handle 0 when no slot is free or the connection is not up.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_open_stream`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `event`.

## Function `quic_on_stream_write`

Queues bytes on a stream.

### Signature

```
quic_on_stream_write(event)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `event` | input | [`StreamWriteEvent`](node.md#type-streamwriteevent) |

### Function does

- Adds the bytes to the send queue as one chunk.
- Resets the stream with code 0 when its queue would pass `stream_queue` or the heap cannot hold the chunk.
- Ignores a stream the application closed or reset.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_stream_write`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `event`.

## Function `quic_on_stream_close`

Ends the bytes of a stream.

### Signature

```
quic_on_stream_close(event)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `event` | input | [`StreamCloseEvent`](node.md#type-streamcloseevent) |

### Function does

- A FIN follows the queue.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_stream_close`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `event`.

## Function `quic_on_stream_reset`

Resets a stream for the application.

### Signature

```
quic_on_stream_reset(event)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `event` | input | [`StreamResetEvent`](node.md#type-streamresetevent) |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_stream_reset`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `event`.

## Function `quic_stream_reset_local`

Resets a stream both ways.

### Signature

```
quic_stream_reset_local(stream, code)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `stream` | input | a stream slot |
| `code` | input | u64: the application error code |

### Function does

- Sends RESET_STREAM and STOP_SENDING with the code.
- Drops the queue.
- Stops taking the data of the peer.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_reset_local`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `stream`, `code`.

## Function `quic_stream_drop`

Frees the send queue of a stream.

### Signature

```
quic_stream_drop()
```

### Function does

- Frees its segments too when its receive side is over.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_drop`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the stream in x20, rbp, s2.

## Function `quic_stream_drop_rx`

Frees the received segments of a stream.

### Signature

```
quic_stream_drop_rx()
```

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_drop_rx`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the stream in x20, rbp, s2.

## Function `quic_stream_acked`

Handles an acknowledged STREAM frame.

### Signature

```
quic_stream_acked(stream, offset, len, fin)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `stream` | input | a stream slot |
| `offset` | input | u64 |
| `len` | input | u64 |
| `fin` | input | u64: 1 with the FIN |

### Function does

- Adds the range to the acknowledged ranges.
- Moves the acknowledged offset over every range that touches it, and frees the chunks below it.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_acked`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `stream`, `offset`, `len`, `fin`.

## Function `quic_stream_advance`

Moves the acknowledged offset of a stream.

### Signature

```
quic_stream_advance()
```

### Function does

- Moves it over the acknowledged ranges that touch it.
- Frees the chunks wholly below it.
- Marks the stream when its data and FIN are all acknowledged.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_advance`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the stream in x20, rbp, s2.

## Function `quic_stream_lost`

Handles a lost STREAM frame.

### Signature

```
quic_stream_lost(stream, offset, len, fin)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `stream` | input | a stream slot |
| `offset` | input | u64 |
| `len` | input | u64 |
| `fin` | input | u64: 1 with the FIN |

### Function does

- Adds the part not yet acknowledged to the lost ranges.
- Sends a lost FIN again.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_lost`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `stream`, `offset`, `len`, `fin`.

## Function `quic_stream_reset_acked`

Ends our side of a reset stream.

### Signature

```
quic_stream_reset_acked(stream)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `stream` | input | a stream slot |

### Function does

- Our RESET_STREAM is acknowledged, so our side is over.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_reset_acked`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `stream`.

## Function `quic_ranges_add`

Adds a range to a stream range list.

### Signature

```
quic_ranges_add(stream, start, end, list, max)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `stream` | input | a stream slot |
| `start` | input | u64 |
| `end` | input | u64 |
| `list` | input and output | a u8 count, other bits kept, then `max` pairs at list + 8 |
| `max` | input | u64 |

### Function does

- Keeps the ranges in order and joined.
- Joins the range to the last one, gap included, when the list is full.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_ranges_add`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `stream`, `start`, `end`, `list`, `max`.

## Function `quic_ranges_remove`

Removes a range from a stream range list.

### Signature

```
quic_ranges_remove(stream, list, index)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `stream` | input | a stream slot |
| `list` | input and output | a range list |
| `index` | input | u64 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_ranges_remove`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `stream`, `list`, `index`.

## Function `quic_peer_stream`

Finds the stream of a frame of the peer.

### Signature

```
quic_peer_stream(id) -> (stream, error)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `id` | input | u64 |

### Function does

- Opens a new stream the peer may open, with every lower one of its kind (RFC 9000 section 3.2).
- Returns the stream, or 0 when the frame is to be ignored, and 0 or the error code.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_peer_stream`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- It returns two values: x0, rax or a0, then x1, rdx or a1.
- Argument order: `id`.

## Function `quic_rx_limits`

Checks the flow control of the stream and the connection, and the final size rules, for data up to end (RFC 9000 sections 4.1 and 4.5).

### Signature

```
quic_rx_limits(stream, end) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `stream` | input | a stream slot |
| `end` | input | u64 |

### Function does

- Raises the highest offsets seen.
- Returns 0, or the error code to close the connection with.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_rx_limits`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `stream`, `end`.

## Function `quic_on_stream_frame`

Handles a STREAM frame.

### Signature

```
quic_on_stream_frame(id, offset, data, len, fin) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `id` | input | u64 |
| `offset` | input | u64 |
| `data` | input | `len` bytes |
| `len` | input | u64 |
| `fin` | input | u64: 1 with the FIN |

### Function does

- Adds the bytes past those delivered to the segments of the stream, in order, overlaps cut.
- Returns 0, or the error code to close the connection with.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_stream_frame`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `id`, `offset`, `data`, `len`, `fin`.

## Function `quic_segment_add`

Stores received bytes.

### Signature

```
quic_segment_add(stream, offset, data, len) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `stream` | input | a stream slot |
| `offset` | input | u64 |
| `data` | input | `len` bytes |
| `len` | input | u64 |

### Function does

- Puts the bytes not held yet into new segments in order.
- Returns 0, or INTERNAL_ERROR when the heap has no room.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_segment_add`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `stream`, `offset`, `data`, `len`.

## Function `quic_on_reset_stream`

Handles a RESET_STREAM frame.

### Signature

```
quic_on_reset_stream(id, code, final) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `id` | input | u64 |
| `code` | input | u64 |
| `final` | input | u64: the final size |

### Function does

- Checks and counts the final size.
- Frees the segments.
- The application hears STREAM_RESET with the code.
- Returns 0, or the error code to close the connection with.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_reset_stream`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `id`, `code`, `final`.

## Function `quic_on_stop_sending`

Handles a STOP_SENDING frame.

### Signature

```
quic_on_stop_sending(id, code) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `id` | input | u64 |
| `code` | input | u64 |

### Function does

- Sends RESET_STREAM (RFC 9000 section 3.5).
- The application hears STREAM_RESET with the code.
- Returns 0, or the error code to close the connection with.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_stop_sending`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `id`, `code`.

## Function `quic_on_max_stream_data`

Handles a MAX_STREAM_DATA frame.

### Signature

```
quic_on_max_stream_data(id, max) -> error
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `id` | input | u64 |
| `max` | input | u64 |

### Function does

- Raises the send limit of the stream.
- Returns 0, or the error code to close the connection with.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_max_stream_data`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `id`, `max`.

## Function `quic_stream_tell`

Tells the application what happened on a stream.

### Signature

```
quic_stream_tell(stream) -> freed
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `stream` | input | a stream slot |

### Function does

- Adds STREAM_OPENED, STREAM_DATA of the bytes in order, STREAM_FIN and STREAM_RESET while the action room allows.
- Gives new flow control credit.
- Returns 1 when the stream is over and freed, else 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_tell`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `stream`.

## Function `quic_stream_credit`

Gives new flow control credit.

### Signature

```
quic_stream_credit()
```

### Function does

- Asks for MAX_STREAM_DATA when half the window of the stream is used.
- Asks for MAX_DATA when half that of the connection is used.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_credit`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1; the stream in x20, rbp, s2.

## Test vectors

- Scenarios
  - File: [tests/runner/runner.c](../../tests/runner/runner.c): handshake, reset and limits.
- Shell loop test
  - File: [tests/shell/loop.c](../../tests/shell/loop.c): a 256 KiB echo on one stream.

## Results

<!-- CI generates the tick table for each function here. -->

### `quic_stream_new`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_stream_free`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_stream_find`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_assign_ids`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_on_open_stream`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_on_stream_write`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_on_stream_close`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_on_stream_reset`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_stream_reset_local`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_stream_drop`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_stream_drop_rx`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_stream_acked`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_stream_advance`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_stream_lost`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_stream_reset_acked`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_ranges_add`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_ranges_remove`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_peer_stream`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_rx_limits`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_on_stream_frame`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_segment_add`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_on_reset_stream`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_on_stop_sending`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_on_max_stream_data`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_stream_tell`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_stream_credit`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |
